use hydra_core::{
    Action, ActionPayloadSchema, Claim, ClaimPredicateSchema, EdgeId, EdgeTypeSchema,
    EntityTypeSchema, Evidence, EvidencePayloadSchema, Policy, PolicyConditionSchema,
    SchemaDefinition, SchemaId, TypeId, Value,
};
use hydra_engine::hydra::Hydra;
use hydra_engine::schema_validator::SchemaValidationReport;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Read-only schema/introspection/validation service.
///
/// This is the public-facing schema API surface for clients that want to:
/// - inspect registered schemas
/// - preflight payloads before attempting writes
/// - mirror the same validation logic used by strict SchemaGate
///
/// Mirrors QueryService's concurrency model: tokio::sync::RwLock + async
/// readers. All methods acquire the read lock only — ingestion holds the
/// write lock independently.
#[derive(Clone)]
pub struct SchemaService {
    hydra: Arc<RwLock<Hydra>>,
}

impl SchemaService {
    pub(crate) fn new(hydra: Arc<RwLock<Hydra>>) -> Self {
        Self { hydra }
    }

    // === Registry introspection ===

    pub async fn schema(&self, id: &SchemaId) -> Option<SchemaDefinition> {
        self.hydra.read().await.schema(id).cloned()
    }

    pub async fn active_schemas(&self) -> Vec<SchemaDefinition> {
        self.hydra
            .read()
            .await
            .active_schemas()
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn disabled_schemas(&self) -> Vec<SchemaDefinition> {
        self.hydra
            .read()
            .await
            .disabled_schemas()
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn archived_schemas(&self) -> Vec<SchemaDefinition> {
        self.hydra
            .read()
            .await
            .archived_schemas()
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn entity_schema(&self, type_id: &TypeId) -> Option<EntityTypeSchema> {
        self.hydra.read().await.entity_schema(type_id).cloned()
    }

    /// Edge type schema lookup — Edge Gating Patch 2.
    pub async fn edge_schema(&self, type_id: &TypeId) -> Option<EdgeTypeSchema> {
        self.hydra.read().await.edge_schema(type_id).cloned()
    }

    pub async fn evidence_schema(&self, kind: &str) -> Option<EvidencePayloadSchema> {
        self.hydra.read().await.evidence_schema(kind).cloned()
    }

    pub async fn claim_predicate_schema(&self, predicate: &str) -> Option<ClaimPredicateSchema> {
        self.hydra
            .read()
            .await
            .claim_predicate_schema(predicate)
            .cloned()
    }

    pub async fn action_payload_schema(&self, action_kind: &str) -> Option<ActionPayloadSchema> {
        self.hydra
            .read()
            .await
            .action_payload_schema(action_kind)
            .cloned()
    }

    pub async fn policy_condition_schema(
        &self,
        policy_kind: &str,
    ) -> Option<PolicyConditionSchema> {
        self.hydra
            .read()
            .await
            .policy_condition_schema(policy_kind)
            .cloned()
    }

    // === Preflight validation ===
    //
    // These mirror the validation logic SchemaGate runs in strict mode, so
    // clients can ask "would this payload pass?" before attempting the write.

    pub async fn validate_action_payload(&self, action: &Action) -> SchemaValidationReport {
        self.hydra.read().await.validate_action_payload(action)
    }

    pub async fn validate_policy_condition(&self, policy: &Policy) -> SchemaValidationReport {
        self.hydra.read().await.validate_policy_condition(policy)
    }

    pub async fn validate_evidence(&self, evidence: &Evidence) -> SchemaValidationReport {
        self.hydra.read().await.validate_evidence(evidence)
    }

    pub async fn validate_claim(&self, claim: &Claim) -> SchemaValidationReport {
        self.hydra.read().await.validate_claim(claim)
    }

    pub async fn validate_node_create(
        &self,
        type_id: &TypeId,
        properties: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        self.hydra
            .read()
            .await
            .validate_node_create(type_id, properties)
    }

    pub async fn validate_node_update(
        &self,
        type_id: &TypeId,
        changes: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        self.hydra
            .read()
            .await
            .validate_node_update(type_id, changes)
    }

    /// Preflight an edge create against the registered EdgeTypeSchema
    /// (if any). Unknown-schema policy is the SchemaGate's
    /// responsibility — this method returns `valid(None)` for
    /// unregistered types, same as `validate_node_create`.
    pub async fn validate_edge_create(
        &self,
        type_id: &TypeId,
        properties: &HashMap<String, Value>,
    ) -> SchemaValidationReport {
        self.hydra
            .read()
            .await
            .validate_edge_create(type_id, properties)
    }

    /// Preflight an edge update. Returns `None` when the edge id
    /// doesn't exist so HTTP callers can 404 — mirrors
    /// [`hydra_engine::hydra::Hydra::validate_edge_update`].
    pub async fn validate_edge_update(
        &self,
        edge_id: &EdgeId,
        changes: &HashMap<String, Value>,
    ) -> Option<SchemaValidationReport> {
        self.hydra
            .read()
            .await
            .validate_edge_update(edge_id, changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_core::{
        Action, ActionId, ActionKind, ActionPayloadSchema, ActionStatus, ActionTarget, ActorId,
        EntityTypeSchema, EventKind, FieldSchema, SchemaDefinition, SchemaId, SchemaStatus,
        TypeId, ValueType,
    };
    use std::collections::HashMap;

    fn actor() -> ActorId {
        ActorId::from_str("actor_schema_service")
    }

    fn shared_hydra() -> Arc<RwLock<Hydra>> {
        Arc::new(RwLock::new(Hydra::new()))
    }

    fn register_action_schema(hydra: &mut Hydra) {
        let now = chrono::Utc::now();
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
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::ActionPayload(schema),
            })
            .unwrap();
    }

    fn register_entity_schema(hydra: &mut Hydra) {
        let now = chrono::Utc::now();
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
        hydra
            .ingest(EventKind::SchemaRegistered {
                schema: SchemaDefinition::EntityType(schema),
            })
            .unwrap();
    }

    fn action(payload: HashMap<String, hydra_core::Value>) -> Action {
        let now = chrono::Utc::now();
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

    #[tokio::test]
    async fn schema_service_exposes_registered_schemas() {
        let hydra = shared_hydra();
        {
            let mut guard = hydra.write().await;
            register_action_schema(&mut guard);
            register_entity_schema(&mut guard);
        }
        let service = SchemaService::new(hydra);
        assert_eq!(service.active_schemas().await.len(), 2);
        assert!(service
            .action_payload_schema("PostLedgerEntry")
            .await
            .is_some());
        assert!(service
            .entity_schema(&TypeId::from_str("type_invoice"))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn schema_service_validates_action_payload() {
        let hydra = shared_hydra();
        {
            let mut guard = hydra.write().await;
            register_action_schema(&mut guard);
        }
        let service = SchemaService::new(hydra);
        let mut payload = HashMap::new();
        payload.insert(
            "account".to_string(),
            hydra_core::Value::String("Cash".to_string()),
        );
        payload.insert("amount".to_string(), hydra_core::Value::Float(100.0));
        let report = service.validate_action_payload(&action(payload)).await;
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[tokio::test]
    async fn schema_service_reports_invalid_action_payload() {
        let hydra = shared_hydra();
        {
            let mut guard = hydra.write().await;
            register_action_schema(&mut guard);
        }
        let service = SchemaService::new(hydra);
        let mut payload = HashMap::new();
        payload.insert(
            "account".to_string(),
            hydra_core::Value::String("Cash".to_string()),
        );
        payload.insert(
            "amount".to_string(),
            hydra_core::Value::String("bad".to_string()),
        );
        let report = service.validate_action_payload(&action(payload)).await;
        assert!(report.is_invalid());
        assert_eq!(report.errors[0].path, "amount");
    }

    #[tokio::test]
    async fn schema_service_validates_node_create() {
        let hydra = shared_hydra();
        {
            let mut guard = hydra.write().await;
            register_entity_schema(&mut guard);
        }
        let service = SchemaService::new(hydra);
        let mut properties = HashMap::new();
        properties.insert(
            "invoice_number".to_string(),
            hydra_core::Value::String("INV-001".to_string()),
        );
        properties.insert("amount".to_string(), hydra_core::Value::Float(100.0));
        let report = service
            .validate_node_create(&TypeId::from_str("type_invoice"), &properties)
            .await;
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }

    #[tokio::test]
    async fn schema_service_validates_node_update() {
        let hydra = shared_hydra();
        {
            let mut guard = hydra.write().await;
            register_entity_schema(&mut guard);
        }
        let service = SchemaService::new(hydra);
        let mut changes = HashMap::new();
        changes.insert("amount".to_string(), hydra_core::Value::Float(125.0));
        let report = service
            .validate_node_update(&TypeId::from_str("type_invoice"), &changes)
            .await;
        assert!(report.is_valid());
        assert!(report.schema_id.is_some());
    }
}
