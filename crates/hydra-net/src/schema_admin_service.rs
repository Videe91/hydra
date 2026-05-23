use hydra_core::error::Result;
use hydra_core::{
    ActionPayloadSchema, ActorId, ClaimPredicateSchema, EntityTypeSchema, EventKind,
    EvidencePayloadSchema, FieldSchema, PolicyConditionSchema, SchemaDefinition, SchemaId,
    SchemaStatus, TenantId, TypeId, ValueType,
};
use hydra_engine::hydra::Hydra;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Ergonomic builder for schema field lists.
///
/// Mirrors hydra-sdk::SchemaFields so async/runtime callers can construct
/// schemas without manually building Vec<FieldSchema>. Re-implemented here
/// to keep hydra-net free of an hydra-sdk dependency.
#[derive(Debug, Clone, Default)]
pub struct SchemaFields {
    fields: Vec<FieldSchema>,
}

impl SchemaFields {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn required(mut self, name: impl Into<String>, value_type: ValueType) -> Self {
        self.fields.push(FieldSchema::required(name, value_type));
        self
    }

    pub fn optional(mut self, name: impl Into<String>, value_type: ValueType) -> Self {
        self.fields.push(FieldSchema::optional(name, value_type));
        self
    }

    pub fn field(mut self, field: FieldSchema) -> Self {
        self.fields.push(field);
        self
    }

    pub fn build(self) -> Vec<FieldSchema> {
        self.fields
    }
}

/// Async schema administration service.
///
/// Write-side counterpart to SchemaService:
/// - SchemaService introspects and validates (read lock).
/// - SchemaAdminService registers / disables / archives schemas (write lock).
///
/// All schema changes flow through Hydra::ingest, so they remain
/// event-sourced, committed, recoverable, and immediately visible through
/// SchemaService after the await returns.
#[derive(Clone)]
pub struct SchemaAdminService {
    hydra: Arc<RwLock<Hydra>>,
    default_actor: ActorId,
    tenant_id: Option<TenantId>,
}

impl SchemaAdminService {
    pub(crate) fn new(hydra: Arc<RwLock<Hydra>>, default_actor: ActorId) -> Self {
        Self {
            hydra,
            default_actor,
            tenant_id: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_tenant(
        hydra: Arc<RwLock<Hydra>>,
        default_actor: ActorId,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            hydra,
            default_actor,
            tenant_id: Some(tenant_id),
        }
    }

    pub fn default_actor(&self) -> &ActorId {
        &self.default_actor
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    pub async fn register_entity_schema(
        &self,
        type_id: TypeId,
        name: impl Into<String>,
        fields: Vec<FieldSchema>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            type_id,
            name: name.into(),
            status: SchemaStatus::Active,
            fields,
            created_by: self.default_actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EntityType(schema),
            })?;
        Ok(schema_id)
    }

    pub async fn register_evidence_schema(
        &self,
        kind: impl Into<String>,
        fields: Vec<FieldSchema>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            kind: kind.into(),
            status: SchemaStatus::Active,
            fields,
            created_by: self.default_actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EvidencePayload(schema),
            })?;
        Ok(schema_id)
    }

    pub async fn register_claim_predicate_schema(
        &self,
        predicate: impl Into<String>,
        subject_type: Option<TypeId>,
        object_type: ValueType,
        allowed_claim_kinds: Vec<String>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            predicate: predicate.into(),
            status: SchemaStatus::Active,
            subject_type,
            object_type,
            allowed_claim_kinds,
            created_by: self.default_actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ClaimPredicate(schema),
            })?;
        Ok(schema_id)
    }

    pub async fn register_action_payload_schema(
        &self,
        action_kind: impl Into<String>,
        fields: Vec<FieldSchema>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            action_kind: action_kind.into(),
            status: SchemaStatus::Active,
            fields,
            created_by: self.default_actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })?;
        Ok(schema_id)
    }

    pub async fn register_policy_condition_schema(
        &self,
        policy_kind: impl Into<String>,
        fields: Vec<FieldSchema>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            policy_kind: policy_kind.into(),
            status: SchemaStatus::Active,
            fields,
            created_by: self.default_actor.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::PolicyCondition(schema),
            })?;
        Ok(schema_id)
    }

    pub async fn disable_schema(
        &self,
        schema_id: SchemaId,
        reason: Option<String>,
    ) -> Result<()> {
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaDisabled {
                schema_id,
                disabled_by: self.default_actor.clone(),
                reason,
            })?;
        Ok(())
    }

    pub async fn archive_schema(
        &self,
        schema_id: SchemaId,
        reason: Option<String>,
    ) -> Result<()> {
        self.hydra
            .write()
            .await
            .ingest(EventKind::SchemaArchived {
                schema_id,
                archived_by: self.default_actor.clone(),
                reason,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;

    #[tokio::test]
    async fn schema_fields_builder_builds_required_and_optional_fields() {
        let fields = SchemaFields::new()
            .required("amount", ValueType::Float)
            .optional("memo", ValueType::String)
            .build();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "amount");
        assert!(fields[0].required);
        assert_eq!(fields[1].name, "memo");
        assert!(!fields[1].required);
    }

    #[tokio::test]
    async fn schema_admin_service_registers_entity_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let schema_id = runtime
            .schema_admin()
            .register_entity_schema(
                TypeId::from_str("type_invoice"),
                "Invoice",
                SchemaFields::new()
                    .required("invoice_number", ValueType::String)
                    .required("amount", ValueType::Float)
                    .build(),
            )
            .await
            .unwrap();
        assert!(runtime.schema().schema(&schema_id).await.is_some());
        assert!(runtime
            .schema()
            .entity_schema(&TypeId::from_str("type_invoice"))
            .await
            .is_some());
        assert_eq!(runtime.schema().active_schemas().await.len(), 1);
    }

    #[tokio::test]
    async fn schema_admin_service_registers_action_schema_and_validates_payload() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        runtime
            .schema_admin()
            .register_action_payload_schema(
                "PostLedgerEntry",
                SchemaFields::new()
                    .required("account", ValueType::String)
                    .required("amount", ValueType::Float)
                    .build(),
            )
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert(
            "account".to_string(),
            hydra_core::Value::String("Cash".to_string()),
        );
        payload.insert("amount".to_string(), hydra_core::Value::Float(100.0));
        let action = hydra_core::Action {
            id: hydra_core::ActionId::new(),
            tenant_id: None,
            kind: hydra_core::ActionKind::PostLedgerEntry,
            status: hydra_core::ActionStatus::Proposed,
            targets: vec![hydra_core::ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: ActorId::from_str("actor_schema_admin_test"),
            approved_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            executed_at: None,
            caused_by: None,
        };
        let report = runtime.schema().validate_action_payload(&action).await;
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[tokio::test]
    async fn schema_admin_service_disables_and_archives_schema() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let schema_id = runtime
            .schema_admin()
            .register_policy_condition_schema(
                "AutoApproval",
                SchemaFields::new()
                    .required("max_amount", ValueType::Float)
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(runtime.schema().active_schemas().await.len(), 1);

        runtime
            .schema_admin()
            .disable_schema(schema_id.clone(), Some("testing disable".to_string()))
            .await
            .unwrap();
        assert_eq!(runtime.schema().active_schemas().await.len(), 0);
        assert_eq!(runtime.schema().disabled_schemas().await.len(), 1);

        runtime
            .schema_admin()
            .archive_schema(schema_id.clone(), Some("testing archive".to_string()))
            .await
            .unwrap();
        assert_eq!(runtime.schema().disabled_schemas().await.len(), 0);
        assert_eq!(runtime.schema().archived_schemas().await.len(), 1);
        assert_eq!(
            runtime.schema().schema(&schema_id).await.unwrap().status(),
            &SchemaStatus::Archived
        );
    }

    #[tokio::test]
    async fn schema_admin_service_registers_all_schema_kinds() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let admin = runtime.schema_admin();
        admin
            .register_entity_schema(
                TypeId::from_str("type_invoice"),
                "Invoice",
                SchemaFields::new()
                    .required("invoice_number", ValueType::String)
                    .build(),
            )
            .await
            .unwrap();
        admin
            .register_evidence_schema(
                "bank_transaction",
                SchemaFields::new()
                    .required("amount", ValueType::Float)
                    .required("currency", ValueType::String)
                    .build(),
            )
            .await
            .unwrap();
        admin
            .register_claim_predicate_schema(
                "is_stale",
                Some(TypeId::from_str("type_dataset")),
                ValueType::Bool,
                vec!["AnomalyFinding".to_string()],
            )
            .await
            .unwrap();
        admin
            .register_action_payload_schema(
                "Backfill",
                SchemaFields::new()
                    .required("dataset", ValueType::String)
                    .build(),
            )
            .await
            .unwrap();
        admin
            .register_policy_condition_schema(
                "HumanApproval",
                SchemaFields::new()
                    .required("required_role", ValueType::String)
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(runtime.schema().active_schemas().await.len(), 5);
        assert!(runtime
            .schema()
            .entity_schema(&TypeId::from_str("type_invoice"))
            .await
            .is_some());
        assert!(runtime
            .schema()
            .evidence_schema("bank_transaction")
            .await
            .is_some());
        assert!(runtime
            .schema()
            .claim_predicate_schema("is_stale")
            .await
            .is_some());
        assert!(runtime
            .schema()
            .action_payload_schema("Backfill")
            .await
            .is_some());
        assert!(runtime
            .schema()
            .policy_condition_schema("HumanApproval")
            .await
            .is_some());
    }
}
