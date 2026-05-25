use crate::event::Value;
use crate::id::{ActorId, SchemaId, TenantId, TypeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle for registered schemas.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchemaStatus {
    Active,
    Disabled,
    Archived,
}

/// Basic value kinds Hydra can validate.
///
/// v0 intentionally mirrors Hydra's generic Value enum while staying
/// independent enough for schema declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueType {
    Null,
    Bool,
    Int,
    Float,
    String,
    Timestamp,
    List(Box<ValueType>),
    Object,
    Any,
    Custom(TypeId),
}

/// One field in a schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldSchema {
    pub name: String,
    pub value_type: ValueType,
    pub required: bool,
    /// Optional default value for omitted fields.
    pub default_value: Option<Value>,
    /// Human/docs metadata.
    pub description: Option<String>,
    pub metadata: HashMap<String, Value>,
}

impl FieldSchema {
    pub fn required(name: impl Into<String>, value_type: ValueType) -> Self {
        Self {
            name: name.into(),
            value_type,
            required: true,
            default_value: None,
            description: None,
            metadata: HashMap::new(),
        }
    }

    pub fn optional(name: impl Into<String>, value_type: ValueType) -> Self {
        Self {
            name: name.into(),
            value_type,
            required: false,
            default_value: None,
            description: None,
            metadata: HashMap::new(),
        }
    }
}

/// A schema for a graph/entity type.
///
/// Examples:
/// - Dataset
/// - Invoice
/// - BankTransaction
/// - Employee
/// - PayrollRun
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityTypeSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    pub type_id: TypeId,
    pub name: String,
    pub status: SchemaStatus,
    pub fields: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Schema for an edge type. Closes the typed-write gap that
/// EntityTypeSchema covers for nodes: an `EdgeCreated { type_id, ... }`
/// must conform to the schema registered for that edge type when the
/// SchemaGate is in Strict mode.
///
/// Example:
/// - "DependsOn" — edges between services
/// - "in_vpc"    — connects a host to its VPC
/// - "owns"      — connects an account to a resource
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeTypeSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    pub type_id: TypeId,
    pub name: String,
    pub status: SchemaStatus,
    pub fields: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Schema for an evidence payload kind.
///
/// Example:
/// kind = "bank_transaction"
/// required fields = amount, currency, posted_at, counterparty
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePayloadSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    pub kind: String,
    pub status: SchemaStatus,
    pub fields: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Schema for a claim predicate.
///
/// Example:
/// predicate = "matches_invoice"
/// subject_type = BankTransaction
/// object_type = Invoice
///
/// predicate = "is_stale"
/// subject_type = Dataset
/// object_type = Bool
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimPredicateSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    pub predicate: String,
    pub status: SchemaStatus,
    pub subject_type: Option<TypeId>,
    pub object_type: ValueType,
    pub allowed_claim_kinds: Vec<String>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Schema for an action payload.
///
/// Example:
/// ActionKind::Backfill requires { dataset: String }
/// ActionKind::PostLedgerEntry requires { account, amount, currency }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionPayloadSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    /// Stable action kind key, e.g. "Backfill", "PostLedgerEntry", "Custom:Foo".
    pub action_kind: String,
    pub status: SchemaStatus,
    pub fields: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Schema for policy condition payloads.
///
/// Example:
/// PolicyKind::AutoApproval may require { max_amount: Float }
/// PolicyKind::HumanApproval may require { required_role: String }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyConditionSchema {
    pub id: SchemaId,
    pub tenant_id: Option<TenantId>,
    /// Stable policy kind key, e.g. "AutoApproval", "HumanApproval", "Payroll".
    pub policy_kind: String,
    pub status: SchemaStatus,
    pub fields: Vec<FieldSchema>,
    pub created_by: ActorId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, Value>,
}

/// Unified schema envelope.
///
/// This lets one event and one future SchemaRegistryStore materialize all
/// schema kinds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SchemaDefinition {
    EntityType(EntityTypeSchema),
    EdgeType(EdgeTypeSchema),
    EvidencePayload(EvidencePayloadSchema),
    ClaimPredicate(ClaimPredicateSchema),
    ActionPayload(ActionPayloadSchema),
    PolicyCondition(PolicyConditionSchema),
}

impl SchemaDefinition {
    pub fn id(&self) -> &SchemaId {
        match self {
            SchemaDefinition::EntityType(schema) => &schema.id,
            SchemaDefinition::EdgeType(schema) => &schema.id,
            SchemaDefinition::EvidencePayload(schema) => &schema.id,
            SchemaDefinition::ClaimPredicate(schema) => &schema.id,
            SchemaDefinition::ActionPayload(schema) => &schema.id,
            SchemaDefinition::PolicyCondition(schema) => &schema.id,
        }
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            SchemaDefinition::EntityType(schema) => schema.tenant_id.as_ref(),
            SchemaDefinition::EdgeType(schema) => schema.tenant_id.as_ref(),
            SchemaDefinition::EvidencePayload(schema) => schema.tenant_id.as_ref(),
            SchemaDefinition::ClaimPredicate(schema) => schema.tenant_id.as_ref(),
            SchemaDefinition::ActionPayload(schema) => schema.tenant_id.as_ref(),
            SchemaDefinition::PolicyCondition(schema) => schema.tenant_id.as_ref(),
        }
    }

    pub fn status(&self) -> &SchemaStatus {
        match self {
            SchemaDefinition::EntityType(schema) => &schema.status,
            SchemaDefinition::EdgeType(schema) => &schema.status,
            SchemaDefinition::EvidencePayload(schema) => &schema.status,
            SchemaDefinition::ClaimPredicate(schema) => &schema.status,
            SchemaDefinition::ActionPayload(schema) => &schema.status,
            SchemaDefinition::PolicyCondition(schema) => &schema.status,
        }
    }

    pub fn status_mut(&mut self) -> &mut SchemaStatus {
        match self {
            SchemaDefinition::EntityType(schema) => &mut schema.status,
            SchemaDefinition::EdgeType(schema) => &mut schema.status,
            SchemaDefinition::EvidencePayload(schema) => &mut schema.status,
            SchemaDefinition::ClaimPredicate(schema) => &mut schema.status,
            SchemaDefinition::ActionPayload(schema) => &mut schema.status,
            SchemaDefinition::PolicyCondition(schema) => &mut schema.status,
        }
    }

    pub fn updated_at_mut(&mut self) -> &mut DateTime<Utc> {
        match self {
            SchemaDefinition::EntityType(schema) => &mut schema.updated_at,
            SchemaDefinition::EdgeType(schema) => &mut schema.updated_at,
            SchemaDefinition::EvidencePayload(schema) => &mut schema.updated_at,
            SchemaDefinition::ClaimPredicate(schema) => &mut schema.updated_at,
            SchemaDefinition::ActionPayload(schema) => &mut schema.updated_at,
            SchemaDefinition::PolicyCondition(schema) => &mut schema.updated_at,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            SchemaDefinition::EntityType(_) => "entity_type",
            SchemaDefinition::EdgeType(_) => "edge_type",
            SchemaDefinition::EvidencePayload(_) => "evidence_payload",
            SchemaDefinition::ClaimPredicate(_) => "claim_predicate",
            SchemaDefinition::ActionPayload(_) => "action_payload",
            SchemaDefinition::PolicyCondition(_) => "policy_condition",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_test")
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn field_schema_builders_set_required_flag() {
        let required = FieldSchema::required("amount", ValueType::Float);
        let optional = FieldSchema::optional("memo", ValueType::String);
        assert!(required.required);
        assert!(!optional.required);
        assert_eq!(required.name, "amount");
        assert_eq!(optional.name, "memo");
    }

    #[test]
    fn entity_type_schema_serde_roundtrip() {
        let now = now();
        let schema = EntityTypeSchema {
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
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: EntityTypeSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn edge_type_schema_serde_roundtrip() {
        let now = now();
        let schema = EdgeTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("edge_depends_on"),
            name: "DependsOn".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("dependency_type", ValueType::String),
                FieldSchema::optional("discovered_at", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: EdgeTypeSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn schema_definition_common_accessors_cover_edge_type() {
        let now = now();
        let schema = EdgeTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("edge_in_vpc"),
            name: "in_vpc".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("region", ValueType::String)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        let mut definition = SchemaDefinition::EdgeType(schema);
        assert_eq!(definition.id(), &schema_id);
        assert_eq!(definition.tenant_id(), None);
        assert_eq!(*definition.status(), SchemaStatus::Active);
        assert_eq!(definition.kind_name(), "edge_type");
        *definition.status_mut() = SchemaStatus::Disabled;
        assert_eq!(*definition.status(), SchemaStatus::Disabled);
        let new_ts = now + chrono::Duration::seconds(1);
        *definition.updated_at_mut() = new_ts;
    }

    #[test]
    fn evidence_payload_schema_serde_roundtrip() {
        let now = now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: None,
            kind: "bank_transaction".to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: EvidencePayloadSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn claim_predicate_schema_serde_roundtrip() {
        let now = now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: None,
            predicate: "is_stale".to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: ClaimPredicateSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn action_payload_schema_serde_roundtrip() {
        let now = now();
        let schema = ActionPayloadSchema {
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
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: ActionPayloadSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn policy_condition_schema_serde_roundtrip() {
        let now = now();
        let schema = PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: None,
            policy_kind: "AutoApproval".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&schema).unwrap();
        let restored: PolicyConditionSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, restored);
    }

    #[test]
    fn schema_definition_exposes_common_fields() {
        let now = now();
        let schema = EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: None,
            type_id: TypeId::from_str("type_dataset"),
            name: "Dataset".to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("name", ValueType::String)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        let mut definition = SchemaDefinition::EntityType(schema);
        assert_eq!(definition.id(), &schema_id);
        assert_eq!(definition.status(), &SchemaStatus::Active);
        assert_eq!(definition.kind_name(), "entity_type");
        *definition.status_mut() = SchemaStatus::Disabled;
        assert_eq!(definition.status(), &SchemaStatus::Disabled);
    }
}
