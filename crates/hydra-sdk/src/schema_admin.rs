use hydra_core::error::Result;
use hydra_core::{
    ActionPayloadSchema, ActorId, ClaimPredicateSchema, EdgeTypeSchema, EntityTypeSchema,
    EventKind, EvidencePayloadSchema, FieldSchema, PolicyConditionSchema, SchemaDefinition,
    SchemaId, SchemaStatus, TenantId, TypeId, ValueType,
};
use hydra_engine::hydra::Hydra;
use std::collections::HashMap;

/// Ergonomic builder for schema field lists.
///
/// ```ignore
/// let fields = SchemaFields::new()
///     .required("amount", ValueType::Float)
///     .optional("memo", ValueType::String)
///     .build();
/// ```
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

/// SDK-facing schema administration API.
///
/// This is a thin wrapper around Hydra ingestion: schema changes remain
/// event-sourced and committed through the normal database path (the same
/// `SchemaRegistered` / `SchemaDisabled` / `SchemaArchived` events you would
/// write by hand). The wrapper just removes the boilerplate of building the
/// full `SchemaDefinition` struct each time.
pub struct SchemaAdmin<'a> {
    hydra: &'a mut Hydra,
    tenant_id: Option<TenantId>,
    actor_id: ActorId,
}

impl<'a> SchemaAdmin<'a> {
    pub fn new(hydra: &'a mut Hydra, actor_id: ActorId) -> Self {
        Self {
            hydra,
            tenant_id: None,
            actor_id,
        }
    }

    pub fn with_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    pub fn register_entity_schema(
        &mut self,
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
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::EntityType(schema),
        })?;
        Ok(schema_id)
    }

    /// Register an [`EdgeTypeSchema`] — Edge Gating Patch 2.
    /// Symmetric with [`Self::register_entity_schema`].
    pub fn register_edge_schema(
        &mut self,
        type_id: TypeId,
        name: impl Into<String>,
        fields: Vec<FieldSchema>,
    ) -> Result<SchemaId> {
        let now = chrono::Utc::now();
        let schema = EdgeTypeSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.clone(),
            type_id,
            name: name.into(),
            status: SchemaStatus::Active,
            fields,
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::EdgeType(schema),
        })?;
        Ok(schema_id)
    }

    pub fn register_evidence_schema(
        &mut self,
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
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::EvidencePayload(schema),
        })?;
        Ok(schema_id)
    }

    pub fn register_claim_predicate_schema(
        &mut self,
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
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::ClaimPredicate(schema),
        })?;
        Ok(schema_id)
    }

    pub fn register_action_payload_schema(
        &mut self,
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
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::ActionPayload(schema),
        })?;
        Ok(schema_id)
    }

    pub fn register_policy_condition_schema(
        &mut self,
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
            created_by: self.actor_id.clone(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        };
        let schema_id = schema.id.clone();
        self.hydra.ingest(EventKind::SchemaRegistered {
            schema: SchemaDefinition::PolicyCondition(schema),
        })?;
        Ok(schema_id)
    }

    pub fn disable_schema(
        &mut self,
        schema_id: SchemaId,
        reason: Option<String>,
    ) -> Result<()> {
        self.hydra.ingest(EventKind::SchemaDisabled {
            schema_id,
            disabled_by: self.actor_id.clone(),
            reason,
        })?;
        Ok(())
    }

    pub fn archive_schema(
        &mut self,
        schema_id: SchemaId,
        reason: Option<String>,
    ) -> Result<()> {
        self.hydra.ingest(EventKind::SchemaArchived {
            schema_id,
            archived_by: self.actor_id.clone(),
            reason,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{Action, ActionId, ActionKind, ActionStatus, ActionTarget, Value};
    use hydra_engine::hydra::Hydra;

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_admin")
    }

    #[test]
    fn schema_fields_builder_builds_required_and_optional_fields() {
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

    #[test]
    fn registers_entity_schema() {
        let mut hydra = Hydra::new();
        let schema_id = {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .register_entity_schema(
                    TypeId::from_str("type_invoice"),
                    "Invoice",
                    SchemaFields::new()
                        .required("invoice_number", ValueType::String)
                        .required("amount", ValueType::Float)
                        .build(),
                )
                .unwrap()
        };
        assert!(hydra.schema(&schema_id).is_some());
        assert!(hydra
            .entity_schema(&TypeId::from_str("type_invoice"))
            .is_some());
        assert_eq!(hydra.active_schemas().len(), 1);
    }

    #[test]
    fn registers_action_schema_and_validates_payload() {
        let mut hydra = Hydra::new();
        {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .register_action_payload_schema(
                    "PostLedgerEntry",
                    SchemaFields::new()
                        .required("account", ValueType::String)
                        .required("amount", ValueType::Float)
                        .build(),
                )
                .unwrap();
        }
        let now = chrono::Utc::now();
        let mut payload = HashMap::new();
        payload.insert("account".to_string(), Value::String("Cash".to_string()));
        payload.insert("amount".to_string(), Value::Float(100.0));
        let action = Action {
            id: ActionId::new(),
            tenant_id: None,
            kind: ActionKind::PostLedgerEntry,
            status: ActionStatus::Proposed,
            targets: vec![ActionTarget::System("ledger".to_string())],
            related_claims: vec![],
            supporting_evidence: vec![],
            proposed_by: actor(),
            approved_by: None,
            rejected_by: None,
            policy_id: None,
            payload,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            executed_at: None,
            caused_by: None,
        };
        let report = hydra.validate_action_payload(&action);
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[test]
    fn disable_and_archive_schema_lifecycle() {
        let mut hydra = Hydra::new();
        let schema_id = {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .register_policy_condition_schema(
                    "AutoApproval",
                    SchemaFields::new()
                        .required("max_amount", ValueType::Float)
                        .build(),
                )
                .unwrap()
        };
        assert_eq!(hydra.active_schemas().len(), 1);

        {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .disable_schema(schema_id.clone(), Some("testing disable".to_string()))
                .unwrap();
        }
        assert_eq!(hydra.active_schemas().len(), 0);
        assert_eq!(hydra.disabled_schemas().len(), 1);

        {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .archive_schema(schema_id.clone(), Some("testing archive".to_string()))
                .unwrap();
        }
        assert_eq!(hydra.disabled_schemas().len(), 0);
        assert_eq!(hydra.archived_schemas().len(), 1);
        assert_eq!(
            hydra.schema(&schema_id).unwrap().status(),
            &SchemaStatus::Archived
        );
    }

    #[test]
    fn registers_all_schema_kinds() {
        let mut hydra = Hydra::new();
        {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .register_entity_schema(
                    TypeId::from_str("type_invoice"),
                    "Invoice",
                    SchemaFields::new()
                        .required("invoice_number", ValueType::String)
                        .build(),
                )
                .unwrap();
            admin
                .register_evidence_schema(
                    "bank_transaction",
                    SchemaFields::new()
                        .required("amount", ValueType::Float)
                        .required("currency", ValueType::String)
                        .build(),
                )
                .unwrap();
            admin
                .register_claim_predicate_schema(
                    "is_stale",
                    Some(TypeId::from_str("type_dataset")),
                    ValueType::Bool,
                    vec!["AnomalyFinding".to_string()],
                )
                .unwrap();
            admin
                .register_action_payload_schema(
                    "Backfill",
                    SchemaFields::new()
                        .required("dataset", ValueType::String)
                        .build(),
                )
                .unwrap();
            admin
                .register_policy_condition_schema(
                    "HumanApproval",
                    SchemaFields::new()
                        .required("required_role", ValueType::String)
                        .build(),
                )
                .unwrap();
        }
        assert_eq!(hydra.active_schemas().len(), 5);
        assert!(hydra
            .entity_schema(&TypeId::from_str("type_invoice"))
            .is_some());
        assert!(hydra.evidence_schema("bank_transaction").is_some());
        assert!(hydra.claim_predicate_schema("is_stale").is_some());
        assert!(hydra.action_payload_schema("Backfill").is_some());
        assert!(hydra.policy_condition_schema("HumanApproval").is_some());
    }

    #[test]
    fn with_tenant_threads_tenant_id_into_registered_schemas() {
        let mut hydra = Hydra::new();
        let tenant = TenantId::from_str("tenant_finance");
        let schema_id = {
            let mut admin =
                SchemaAdmin::new(&mut hydra, actor()).with_tenant(tenant.clone());
            assert_eq!(admin.tenant_id(), Some(&tenant));
            admin
                .register_action_payload_schema(
                    "PostLedgerEntry",
                    SchemaFields::new()
                        .required("amount", ValueType::Float)
                        .build(),
                )
                .unwrap()
        };
        let stored = hydra.schema(&schema_id).unwrap();
        match stored {
            SchemaDefinition::ActionPayload(schema) => {
                assert_eq!(schema.tenant_id.as_ref(), Some(&tenant));
            }
            other => panic!("expected ActionPayload, got {:?}", other.kind_name()),
        }
    }

    // === Edge Gating Patch 2 ===

    #[test]
    fn registers_edge_schema_round_trips() {
        let mut hydra = Hydra::new();
        let schema_id = {
            let mut admin = SchemaAdmin::new(&mut hydra, actor());
            admin
                .register_edge_schema(
                    TypeId::from_str("edge_depends_on"),
                    "DependsOn",
                    SchemaFields::new()
                        .required("dependency_type", ValueType::String)
                        .optional("confidence", ValueType::Float)
                        .build(),
                )
                .unwrap()
        };
        // Generic registry lookup sees it.
        assert!(hydra.schema(&schema_id).is_some());
        // Edge index sees it; entity index does not.
        let edge = hydra
            .edge_schema(&TypeId::from_str("edge_depends_on"))
            .expect("edge schema must be registered");
        assert_eq!(edge.name, "DependsOn");
        assert_eq!(edge.fields.len(), 2);
        assert!(hydra
            .entity_schema(&TypeId::from_str("edge_depends_on"))
            .is_none());
    }
}
