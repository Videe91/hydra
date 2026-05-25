use hydra_core::error::{HydraError, Result};
use hydra_core::{
    ActionPayloadSchema, ClaimPredicateSchema, EdgeTypeSchema, EntityTypeSchema, Event, EventKind,
    EvidencePayloadSchema, PolicyConditionSchema, SchemaDefinition, SchemaId, SchemaStatus, TypeId,
};
use std::collections::{HashMap, HashSet};

/// Materialized schema/type registry state.
///
/// This store answers:
/// - Which schemas are active?
/// - What entity schema owns this TypeId?
/// - What evidence payload schema owns this evidence kind?
/// - What claim predicate schema owns this predicate?
/// - What action payload schema owns this action kind?
/// - What policy condition schema owns this policy kind?
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistryStore {
    schemas: HashMap<SchemaId, SchemaDefinition>,
    schemas_by_status: HashMap<SchemaStatus, HashSet<SchemaId>>,
    entity_schema_by_type_id: HashMap<TypeId, SchemaId>,
    edge_schema_by_type_id: HashMap<TypeId, SchemaId>,
    evidence_schema_by_kind: HashMap<String, SchemaId>,
    claim_schema_by_predicate: HashMap<String, SchemaId>,
    action_schema_by_kind: HashMap<String, SchemaId>,
    policy_schema_by_kind: HashMap<String, SchemaId>,
}

impl SchemaRegistryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    pub fn schema(&self, id: &SchemaId) -> Option<&SchemaDefinition> {
        self.schemas.get(id)
    }

    pub fn all_schemas(&self) -> impl Iterator<Item = &SchemaDefinition> {
        self.schemas.values()
    }

    pub fn schemas_with_status(&self, status: SchemaStatus) -> Vec<&SchemaDefinition> {
        self.schemas_by_status
            .get(&status)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.schemas.get(id))
            .collect()
    }

    pub fn active_schemas(&self) -> Vec<&SchemaDefinition> {
        self.schemas_with_status(SchemaStatus::Active)
    }

    pub fn disabled_schemas(&self) -> Vec<&SchemaDefinition> {
        self.schemas_with_status(SchemaStatus::Disabled)
    }

    pub fn archived_schemas(&self) -> Vec<&SchemaDefinition> {
        self.schemas_with_status(SchemaStatus::Archived)
    }

    pub fn entity_schema(&self, type_id: &TypeId) -> Option<&EntityTypeSchema> {
        let schema_id = self.entity_schema_by_type_id.get(type_id)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::EntityType(schema) => Some(schema),
            _ => None,
        }
    }

    /// Look up the edge type schema registered for a given `TypeId`.
    /// Closes the parallel gap to [`Self::entity_schema`] — Edge
    /// Gating Patch 1.
    pub fn edge_schema(&self, type_id: &TypeId) -> Option<&EdgeTypeSchema> {
        let schema_id = self.edge_schema_by_type_id.get(type_id)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::EdgeType(schema) => Some(schema),
            _ => None,
        }
    }

    pub fn evidence_schema(&self, kind: &str) -> Option<&EvidencePayloadSchema> {
        let schema_id = self.evidence_schema_by_kind.get(kind)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::EvidencePayload(schema) => Some(schema),
            _ => None,
        }
    }

    pub fn claim_predicate_schema(&self, predicate: &str) -> Option<&ClaimPredicateSchema> {
        let schema_id = self.claim_schema_by_predicate.get(predicate)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::ClaimPredicate(schema) => Some(schema),
            _ => None,
        }
    }

    pub fn action_payload_schema(&self, action_kind: &str) -> Option<&ActionPayloadSchema> {
        let schema_id = self.action_schema_by_kind.get(action_kind)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::ActionPayload(schema) => Some(schema),
            _ => None,
        }
    }

    pub fn policy_condition_schema(&self, policy_kind: &str) -> Option<&PolicyConditionSchema> {
        let schema_id = self.policy_schema_by_kind.get(policy_kind)?;
        match self.schemas.get(schema_id)? {
            SchemaDefinition::PolicyCondition(schema) => Some(schema),
            _ => None,
        }
    }

    /// Apply one Hydra event to the schema registry store.
    ///
    /// Non-schema events are ignored.
    pub fn apply_event(&mut self, event: &Event) -> Result<()> {
        match &event.kind {
            EventKind::SchemaRegistered { schema } => {
                self.insert_schema(schema.clone());
            }
            EventKind::SchemaDisabled { schema_id, .. } => {
                self.mutate_schema(schema_id, |schema| {
                    *schema.status_mut() = SchemaStatus::Disabled;
                    *schema.updated_at_mut() = event.timestamp;
                })?;
            }
            EventKind::SchemaArchived { schema_id, .. } => {
                self.mutate_schema(schema_id, |schema| {
                    *schema.status_mut() = SchemaStatus::Archived;
                    *schema.updated_at_mut() = event.timestamp;
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn apply_events<'a>(&mut self, events: impl IntoIterator<Item = &'a Event>) -> Result<()> {
        for event in events {
            self.apply_event(event)?;
        }
        Ok(())
    }

    fn insert_schema(&mut self, schema: SchemaDefinition) {
        let schema_id = schema.id().clone();
        if let Some(existing) = self.schemas.get(&schema_id).cloned() {
            self.remove_schema_indexes(&existing);
        }
        self.schemas.insert(schema_id.clone(), schema);
        if let Some(inserted) = self.schemas.get(&schema_id).cloned() {
            self.insert_schema_indexes(&inserted);
        }
    }

    fn mutate_schema<F>(&mut self, schema_id: &SchemaId, mutation: F) -> Result<()>
    where
        F: FnOnce(&mut SchemaDefinition),
    {
        let mut schema = self
            .schemas
            .remove(schema_id)
            .ok_or_else(|| HydraError::QueryError(format!("unknown schema: {}", schema_id)))?;
        self.remove_schema_indexes(&schema);
        mutation(&mut schema);
        self.insert_schema_indexes(&schema);
        self.schemas.insert(schema_id.clone(), schema);
        Ok(())
    }

    fn insert_schema_indexes(&mut self, schema: &SchemaDefinition) {
        let schema_id = schema.id().clone();
        self.schemas_by_status
            .entry(schema.status().clone())
            .or_default()
            .insert(schema_id.clone());
        match schema {
            SchemaDefinition::EntityType(entity) => {
                self.entity_schema_by_type_id
                    .insert(entity.type_id.clone(), schema_id);
            }
            SchemaDefinition::EdgeType(edge) => {
                self.edge_schema_by_type_id
                    .insert(edge.type_id.clone(), schema_id);
            }
            SchemaDefinition::EvidencePayload(evidence) => {
                self.evidence_schema_by_kind
                    .insert(evidence.kind.clone(), schema_id);
            }
            SchemaDefinition::ClaimPredicate(claim) => {
                self.claim_schema_by_predicate
                    .insert(claim.predicate.clone(), schema_id);
            }
            SchemaDefinition::ActionPayload(action) => {
                self.action_schema_by_kind
                    .insert(action.action_kind.clone(), schema_id);
            }
            SchemaDefinition::PolicyCondition(policy) => {
                self.policy_schema_by_kind
                    .insert(policy.policy_kind.clone(), schema_id);
            }
        }
    }

    fn remove_schema_indexes(&mut self, schema: &SchemaDefinition) {
        let schema_id = schema.id();
        remove_from_index(&mut self.schemas_by_status, schema.status(), schema_id);
        match schema {
            SchemaDefinition::EntityType(entity) => {
                remove_if_points_to(
                    &mut self.entity_schema_by_type_id,
                    &entity.type_id,
                    schema_id,
                );
            }
            SchemaDefinition::EdgeType(edge) => {
                remove_if_points_to(
                    &mut self.edge_schema_by_type_id,
                    &edge.type_id,
                    schema_id,
                );
            }
            SchemaDefinition::EvidencePayload(evidence) => {
                remove_if_points_to(
                    &mut self.evidence_schema_by_kind,
                    &evidence.kind,
                    schema_id,
                );
            }
            SchemaDefinition::ClaimPredicate(claim) => {
                remove_if_points_to(
                    &mut self.claim_schema_by_predicate,
                    &claim.predicate,
                    schema_id,
                );
            }
            SchemaDefinition::ActionPayload(action) => {
                remove_if_points_to(
                    &mut self.action_schema_by_kind,
                    &action.action_kind,
                    schema_id,
                );
            }
            SchemaDefinition::PolicyCondition(policy) => {
                remove_if_points_to(
                    &mut self.policy_schema_by_kind,
                    &policy.policy_kind,
                    schema_id,
                );
            }
        }
    }
}

fn remove_from_index<K, V>(index: &mut HashMap<K, HashSet<V>>, key: &K, value: &V)
where
    K: std::hash::Hash + Eq + Clone,
    V: std::hash::Hash + Eq,
{
    let should_remove_key = if let Some(values) = index.get_mut(key) {
        values.remove(value);
        values.is_empty()
    } else {
        false
    };
    if should_remove_key {
        index.remove(key);
    }
}

fn remove_if_points_to<K>(index: &mut HashMap<K, SchemaId>, key: &K, schema_id: &SchemaId)
where
    K: std::hash::Hash + Eq,
{
    if index
        .get(key)
        .map(|existing| existing == schema_id)
        .unwrap_or(false)
    {
        index.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        ActorId, CascadeId, EventId, FieldSchema, SchemaId, TenantId, Value, ValueType,
    };
    use std::collections::HashMap;

    fn tenant() -> TenantId {
        TenantId::from_str("tenant_schema_registry_store_test")
    }

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_registry")
    }

    fn event(kind: EventKind) -> Event {
        Event {
            id: EventId::new(),
            tenant_id: Some(tenant()),
            timestamp: chrono::Utc::now(),
            kind,
            caused_by: vec![],
            cascade_id: CascadeId::new(),
            cascade_depth: 0,
            cascade_breadth_index: 0,
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    fn entity_schema(type_id: TypeId, name: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::EntityType(EntityTypeSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            type_id,
            name: name.to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("name", ValueType::String)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn evidence_schema(kind: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::EvidencePayload(EvidencePayloadSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            kind: kind.to_string(),
            status: SchemaStatus::Active,
            fields: vec![
                FieldSchema::required("amount", ValueType::Float),
                FieldSchema::required("currency", ValueType::String),
            ],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn claim_schema(predicate: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::ClaimPredicate(ClaimPredicateSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            predicate: predicate.to_string(),
            status: SchemaStatus::Active,
            subject_type: Some(TypeId::from_str("type_dataset")),
            object_type: ValueType::Bool,
            allowed_claim_kinds: vec!["AnomalyFinding".to_string()],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn action_schema(action_kind: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::ActionPayload(ActionPayloadSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            action_kind: action_kind.to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("dataset", ValueType::String)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn policy_schema(policy_kind: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::PolicyCondition(PolicyConditionSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            policy_kind: policy_kind.to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("max_amount", ValueType::Float)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    fn edge_schema(type_id: TypeId, name: &str) -> SchemaDefinition {
        let now = now();
        SchemaDefinition::EdgeType(EdgeTypeSchema {
            id: SchemaId::new(),
            tenant_id: Some(tenant()),
            type_id,
            name: name.to_string(),
            status: SchemaStatus::Active,
            fields: vec![FieldSchema::required("region", ValueType::String)],
            created_by: actor(),
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        })
    }

    #[test]
    fn stores_entity_schema_and_indexes_by_type_id() {
        let mut store = SchemaRegistryStore::new();
        let type_id = TypeId::from_str("type_invoice");
        let schema = entity_schema(type_id.clone(), "Invoice");
        let schema_id = schema.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: schema.clone(),
            }))
            .unwrap();
        assert_eq!(store.schema_count(), 1);
        assert_eq!(store.schema(&schema_id), Some(&schema));
        assert_eq!(store.active_schemas().len(), 1);
        assert_eq!(store.entity_schema(&type_id).unwrap().name, "Invoice");
    }

    #[test]
    fn stores_all_schema_kinds_and_indexes_by_keys() {
        let mut store = SchemaRegistryStore::new();
        let entity_type = TypeId::from_str("type_dataset");
        let entity = entity_schema(entity_type.clone(), "Dataset");
        let evidence = evidence_schema("bank_transaction");
        let claim = claim_schema("is_stale");
        let action = action_schema("Backfill");
        let policy = policy_schema("AutoApproval");
        store
            .apply_events(&[
                event(EventKind::SchemaRegistered { schema: entity }),
                event(EventKind::SchemaRegistered { schema: evidence }),
                event(EventKind::SchemaRegistered { schema: claim }),
                event(EventKind::SchemaRegistered { schema: action }),
                event(EventKind::SchemaRegistered { schema: policy }),
            ])
            .unwrap();
        assert_eq!(store.schema_count(), 5);
        assert!(store.entity_schema(&entity_type).is_some());
        assert!(store.evidence_schema("bank_transaction").is_some());
        assert!(store.claim_predicate_schema("is_stale").is_some());
        assert!(store.action_payload_schema("Backfill").is_some());
        assert!(store.policy_condition_schema("AutoApproval").is_some());
    }

    #[test]
    fn disables_and_archives_schema_with_reindexing() {
        let mut store = SchemaRegistryStore::new();
        let type_id = TypeId::from_str("type_invoice");
        let schema = entity_schema(type_id.clone(), "Invoice");
        let schema_id = schema.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered { schema }))
            .unwrap();
        assert_eq!(store.active_schemas().len(), 1);

        store
            .apply_event(&event(EventKind::SchemaDisabled {
                schema_id: schema_id.clone(),
                disabled_by: actor(),
                reason: Some("test disable".to_string()),
            }))
            .unwrap();
        assert_eq!(store.active_schemas().len(), 0);
        assert_eq!(store.disabled_schemas().len(), 1);
        assert_eq!(
            store.schema(&schema_id).unwrap().status(),
            &SchemaStatus::Disabled
        );

        store
            .apply_event(&event(EventKind::SchemaArchived {
                schema_id: schema_id.clone(),
                archived_by: actor(),
                reason: Some("test archive".to_string()),
            }))
            .unwrap();
        assert_eq!(store.disabled_schemas().len(), 0);
        assert_eq!(store.archived_schemas().len(), 1);
        assert_eq!(
            store.schema(&schema_id).unwrap().status(),
            &SchemaStatus::Archived
        );
    }

    #[test]
    fn replacement_schema_reindexes_unique_key() {
        let mut store = SchemaRegistryStore::new();
        let mut schema = entity_schema(TypeId::from_str("type_invoice"), "Invoice");
        let schema_id = schema.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: schema.clone(),
            }))
            .unwrap();
        assert!(store
            .entity_schema(&TypeId::from_str("type_invoice"))
            .is_some());

        match &mut schema {
            SchemaDefinition::EntityType(entity) => {
                entity.type_id = TypeId::from_str("type_bill");
                entity.name = "Bill".to_string();
            }
            _ => panic!("expected entity schema"),
        }
        store
            .apply_event(&event(EventKind::SchemaRegistered { schema }))
            .unwrap();

        assert!(store
            .entity_schema(&TypeId::from_str("type_invoice"))
            .is_none());
        assert_eq!(
            store
                .entity_schema(&TypeId::from_str("type_bill"))
                .unwrap()
                .name,
            "Bill"
        );
        assert_eq!(store.schema_count(), 1);
        assert!(store.schema(&schema_id).is_some());
    }

    #[test]
    fn newer_schema_overwrites_unique_key_without_losing_index() {
        let mut store = SchemaRegistryStore::new();
        let first = evidence_schema("bank_transaction");
        let first_id = first.id().clone();
        let second = evidence_schema("bank_transaction");
        let second_id = second.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered { schema: first }))
            .unwrap();
        store
            .apply_event(&event(EventKind::SchemaRegistered { schema: second }))
            .unwrap();
        assert_eq!(store.schema_count(), 2);
        assert_eq!(
            store.evidence_schema("bank_transaction").unwrap().id,
            second_id
        );
        assert!(store.schema(&first_id).is_some());
    }

    #[test]
    fn rejects_unknown_schema_lifecycle_transition() {
        let mut store = SchemaRegistryStore::new();
        let result = store.apply_event(&event(EventKind::SchemaDisabled {
            schema_id: SchemaId::new(),
            disabled_by: actor(),
            reason: None,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn non_schema_events_are_noops() {
        let mut store = SchemaRegistryStore::new();
        store
            .apply_event(&event(EventKind::Signal {
                source: hydra_core::NodeId::from_str("test"),
                name: "noop".to_string(),
                payload: HashMap::new(),
            }))
            .unwrap();
        assert_eq!(store.schema_count(), 0);
    }

    #[test]
    fn unused_import_guard() {
        let _ = Value::Bool(true);
    }

    // === Edge Gating Patch 1 ===

    #[test]
    fn register_edge_schema_indexes_by_type_id() {
        let mut store = SchemaRegistryStore::new();
        let type_id = TypeId::from_str("edge_depends_on");
        let schema = edge_schema(type_id.clone(), "DependsOn");
        let schema_id = schema.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered {
                schema: schema.clone(),
            }))
            .unwrap();
        assert_eq!(store.schema_count(), 1);
        assert_eq!(store.schema(&schema_id), Some(&schema));
        assert_eq!(store.active_schemas().len(), 1);
        assert_eq!(store.edge_schema(&type_id).unwrap().name, "DependsOn");
        // Entity index is untouched — edge schemas live in their own
        // index.
        assert!(store.entity_schema(&type_id).is_none());
    }

    #[test]
    fn disable_archive_edge_schema_status_lifecycle() {
        let mut store = SchemaRegistryStore::new();
        let type_id = TypeId::from_str("edge_in_vpc");
        let schema = edge_schema(type_id.clone(), "in_vpc");
        let schema_id = schema.id().clone();
        store
            .apply_event(&event(EventKind::SchemaRegistered { schema }))
            .unwrap();
        assert_eq!(store.active_schemas().len(), 1);

        store
            .apply_event(&event(EventKind::SchemaDisabled {
                schema_id: schema_id.clone(),
                disabled_by: actor(),
                reason: Some("test disable".to_string()),
            }))
            .unwrap();
        assert_eq!(store.active_schemas().len(), 0);
        assert_eq!(store.disabled_schemas().len(), 1);
        assert_eq!(
            store.edge_schema(&type_id).unwrap().status,
            SchemaStatus::Disabled
        );

        store
            .apply_event(&event(EventKind::SchemaArchived {
                schema_id: schema_id.clone(),
                archived_by: actor(),
                reason: None,
            }))
            .unwrap();
        assert_eq!(store.archived_schemas().len(), 1);
        assert_eq!(
            store.edge_schema(&type_id).unwrap().status,
            SchemaStatus::Archived
        );
    }
}
